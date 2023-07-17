import io
import json
import logging
import os
import zipfile
from datetime import datetime

import requests
from nested_lookup import nested_lookup
from rapticoressvc.multi_threading_helper import run_parallel
from rapticoressvc.storage_helpers.files_helper import read_from_json_file
from rapticoressvc.storage_helpers.files_helper import save_to_json_file
from rapticoressvc.storage_helpers.s3_helper import download_data_from_s3
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.storage_helpers.s3_helper import upload_data_to_s3
from rapticoressvc.svcc_constants import STORAGE_LOCAL
from rapticoressvc.svcc_constants import STORAGE_S3

CVE_NVD_DATA_DIRECTORY = "cve_nvd_data"
MAX_WORKERS_INITIAL = min(32, os.cpu_count() + 4)


def update_modification_timestamps(bucket_name, timestamps_file_name, modification_timestamps, storage_type):
    try:
        upload_status = False
        if storage_type == STORAGE_S3:
            s3_client = get_s3_client()
            timestamps_file_key = f"{CVE_NVD_DATA_DIRECTORY}/{timestamps_file_name}"
            upload_status = upload_data_to_s3(s3_client, bucket_name, timestamps_file_key, modification_timestamps)
        elif storage_type == STORAGE_LOCAL:
            file_destination = [bucket_name, CVE_NVD_DATA_DIRECTORY, f'{timestamps_file_name}.json']
            upload_status = save_to_json_file(modification_timestamps, file_destination)
        logging.debug(f"Modification timestamps upload status: {upload_status}")
    except Exception as e:
        logging.exception(e)


def get_modification_timestamps(bucket_name, timestamps_file_name, storage_type):
    modification_timestamps = {}
    try:
        if storage_type == STORAGE_S3:
            s3_client = get_s3_client()
            timestamps_file_key = f"{CVE_NVD_DATA_DIRECTORY}/{timestamps_file_name}"
            modification_timestamps = download_data_from_s3(s3_client, bucket_name, timestamps_file_key)
        elif storage_type == STORAGE_LOCAL:
            file_destination = [bucket_name, CVE_NVD_DATA_DIRECTORY, f'{timestamps_file_name}.json']
            modification_timestamps = read_from_json_file(file_destination)
        modification_timestamps = modification_timestamps or {}
    except Exception as e:
        logging.exception(e)
    return modification_timestamps


def download_extract_zip(url, last_modified_old=None):
    STATUS_NOT_MODIFIED = 304
    headers = {"If-Modified-Since": last_modified_old}
    response = last_modified_old and requests.get(url, headers=headers) or requests.get(url)
    if response.status_code == STATUS_NOT_MODIFIED:
        logging.debug(f"No change in artifact {url} since last update")
        return None, None

    last_modified = response.headers.get("last-modified")
    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
        for zip_info in zip_file.infolist():
            with zip_file.open(zip_info) as the_file:
                file = json.loads(the_file.read())
                return file, last_modified


def get_nvd_file(zip_url, last_modified_old):
    logging.debug(f"Downloading artifact {zip_url}")
    nvd_data, last_modified = download_extract_zip(zip_url, last_modified_old)
    return nvd_data, last_modified


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


def update_nvd_record(cve_nvd_data, args):
    upload_status = False
    bucket_name = args.get("bucket_name")
    storage_type = args.get("storage_type", "")
    try:
        cve = list(cve_nvd_data.keys())[0]
        data = cve_nvd_data[cve]
        if storage_type == STORAGE_S3:
            s3_client = args.get("s3_client")
            cve_key = f"{CVE_NVD_DATA_DIRECTORY}/{cve}"
            upload_status = upload_data_to_s3(s3_client, bucket_name, cve_key, data)
        elif storage_type == STORAGE_LOCAL:
            file_destination = [bucket_name, CVE_NVD_DATA_DIRECTORY, f'{cve}.json']
            upload_status = save_to_json_file(data, file_destination)
    except Exception as e:
        logging.exception(e)
    return upload_status


def update_nvd_records(bucket_name, cve_nvd_data_map, modification_timestamps, storage_type,
                       max_workers=MAX_WORKERS_INITIAL):
    modified_cve_list = []
    upload_statuses = []
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

    s3_client = storage_type == STORAGE_S3 and get_s3_client()
    args = dict(bucket_name=bucket_name, s3_client=s3_client, storage_type=storage_type)
    if modified_cve_list:
        logging.info(f'Uploading {len(modified_cve_list)} new NVD data records...')
        upload_statuses = run_parallel(update_nvd_record, modified_cve_list, args, max_workers)

    return upload_statuses


def update_nvd_data():
    logging.info('Updating NVD data...')
    bucket_name = os.environ.get("BUCKET_NAME")
    storage_type = os.environ.get("STORAGE_TYPE", "")
    if not bucket_name or not storage_type:
        logging.error(f'Missing or incorrect configuration, bucket_name: {bucket_name}, storage_type: {storage_type}')
        return
    timestamps_file_name = "modification_timestamps"
    nvd_data_years = ["2023", "2022", "2021", "2020", "2019", "2018"]

    modification_timestamps = get_modification_timestamps(bucket_name, timestamps_file_name, storage_type)

    for year in nvd_data_years:
        logging.debug(f'Processing NVD data for year: {year}...')
        try:
            zip_url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'
            nvd_file, last_modified = get_nvd_file(zip_url, modification_timestamps.get(zip_url))
            if not nvd_file and not last_modified:
                continue
            modification_timestamps[zip_url] = last_modified

            cve_nvd_data_map = preprocess_nvd_data_for_upload(nvd_file)

            logging.debug(f'Uploading NVD data for year: {year}...')
            upload_statuses = update_nvd_records(
                bucket_name, cve_nvd_data_map, modification_timestamps, storage_type)
            logging.info(f'Uploaded {len(upload_statuses)} new NVD data records for year: {year}, '
                         f'Succeeded: {upload_statuses.count(True)}, Failed: {upload_statuses.count(False)}')
            upload_statuses.count(False) and modification_timestamps.update({zip_url: None})
        except Exception as e:
            logging.exception(e)
        update_modification_timestamps(bucket_name, timestamps_file_name, modification_timestamps, storage_type)


def get_referenced_cves_from_nvd_record(rejected_nvd_record):
    referenced_cves = []
    try:
        nvd_record_json = json.loads(rejected_nvd_record.get("nvd_data") or "") or {}
        descriptions = nvd_record_json.get("cve", {}).get('description', {}).get('description_data') or []
        for description in descriptions:
            _description = str(description.get("value", ""))
            cves = None
            if "All CVE users should reference" in _description:
                cves = _description.split("All CVE users should reference")[1].split(".")[0]
            elif "All CVE users should consult" in _description:
                cves = _description.split("All CVE users should consult")[1].split(".")[0]
            elif "use CVE-" in _description:
                cves = "CVE-" + _description.split("use CVE-")[1].split(".")[0]
            if cves is not None:
                cves = [segment.strip(",[]") for segment in cves.split(" ")
                        if segment.startswith("CVE-") or segment.startswith("[CVE-")]
                [referenced_cves.append(cve) for cve in cves if cve not in referenced_cves]
    except Exception as e:
        logging.exception(e)
    return referenced_cves


def download_nvd_record(cve, args):
    logging.debug(f'Getting NVD data for CVE: {cve}')
    bucket_name = args.get("bucket_name")
    storage_type = args.get("storage_type", "")
    recursion_level = args.get("recursion_level", 1)
    MAX_REFERENCE_LOOKUPS = 3
    nvd_data = {cve: None}
    try:
        nvd_record = None
        if storage_type == STORAGE_S3:
            s3_client = args.get("s3_client")
            cve_key = f"{CVE_NVD_DATA_DIRECTORY}/{cve}"
            nvd_record = download_data_from_s3(s3_client, bucket_name, cve_key)
        elif storage_type == STORAGE_LOCAL:
            file_destination = [bucket_name, CVE_NVD_DATA_DIRECTORY, f'{cve}.json']
            nvd_record = read_from_json_file(file_destination)

        if "** REJECT **" in str(nvd_record):
            if recursion_level <= MAX_REFERENCE_LOOKUPS:
                referenced_cves = get_referenced_cves_from_nvd_record(nvd_record)
                nvd_data = get_nvd_data(referenced_cves, recursion_level=recursion_level+1)
        else:
            nvd_data = {cve: nvd_record}
    except Exception as e:
        logging.exception(e)
    return nvd_data


def get_nvd_data(cves, max_workers=MAX_WORKERS_INITIAL, recursion_level=1):
    cve_nvd_map = {}
    bucket_name = os.environ.get("BUCKET_NAME")
    storage_type = os.environ.get("STORAGE_TYPE", "")
    allowed_storage_medium = [STORAGE_S3, STORAGE_LOCAL]
    if not bucket_name or not storage_type or storage_type not in allowed_storage_medium:
        logging.error(f'Missing or incorrect configuration, bucket_name: {bucket_name}, storage_type: {storage_type}')
        return cve_nvd_map
    try:
        cves = cves if type(cves) is list else [cves]
        s3_client = storage_type == STORAGE_S3 and get_s3_client()
        args = dict(bucket_name=bucket_name, s3_client=s3_client, storage_type=storage_type,
                    recursion_level=recursion_level)
        cve_nvd_list = run_parallel(download_nvd_record, cves, args, max_workers)
        cve_nvd_map = dict((key, cve_nvd_dict[key]) for cve_nvd_dict in cve_nvd_list for key in cve_nvd_dict)
    except Exception as e:
        logging.exception(e)
    return cve_nvd_map
