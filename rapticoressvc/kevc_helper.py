import json
import logging
import os

import requests
from rapticoressvc.storage_helpers.files_helper import read_from_json_file
from rapticoressvc.storage_helpers.files_helper import save_to_json_file
from rapticoressvc.storage_helpers.s3_helper import download_data_from_s3
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.storage_helpers.s3_helper import upload_data_to_s3
from rapticoressvc.svcc_constants import STORAGE_LOCAL
from rapticoressvc.svcc_constants import STORAGE_S3

KEVC_DATA_DIRECTORY = "kevc_data"


def update_kevc_local_data(bucket_name, kevc_file_name, data, storage_type):
    try:
        upload_status = False
        if storage_type == STORAGE_S3:
            s3_client = get_s3_client()
            kevc_file_key = f"{KEVC_DATA_DIRECTORY}/{kevc_file_name}"
            upload_status = upload_data_to_s3(s3_client, bucket_name, kevc_file_key, data)
        elif storage_type == STORAGE_LOCAL:
            file_destination = [bucket_name, KEVC_DATA_DIRECTORY, f'{kevc_file_name}.json']
            upload_status = save_to_json_file(data, file_destination)
        logging.debug(f"KEVC data upload status: {upload_status}")
    except Exception as e:
        logging.exception(e)


def get_kevc_local_data(bucket_name, kevc_file_name, storage_type):
    data = {}
    try:
        if storage_type == STORAGE_S3:
            s3_client = get_s3_client()
            kevc_file_key = f"{KEVC_DATA_DIRECTORY}/{kevc_file_name}"
            data = download_data_from_s3(s3_client, bucket_name, kevc_file_key)
        elif storage_type == STORAGE_LOCAL:
            file_destination = [bucket_name, KEVC_DATA_DIRECTORY, f'{kevc_file_name}.json']
            data = read_from_json_file(file_destination)
        data = data or {}
    except Exception as e:
        logging.exception(e)
    return data


def get_kevc_cisa_data(url, last_modified_old=None):
    logging.debug(f"Downloading artifact {url}")
    data = {}
    last_modified = None
    STATUS_NOT_MODIFIED = 304
    headers = {"If-Modified-Since": last_modified_old}
    try:
        response = last_modified_old and requests.get(
            url, stream=True, headers=headers) or requests.get(url, stream=True)
        if response.status_code == STATUS_NOT_MODIFIED:
            logging.debug(f"No change in artifact {url} since last update")
        elif response.status_code == 200:
            last_modified = response.headers.get("last-modified")
            data = json.loads(response.content)
    except Exception as e:
        logging.exception(e)
    return data, last_modified


def update_kevc_data():
    logging.info('Updating KEVC data...')
    bucket_name = os.environ.get("BUCKET_NAME")
    storage_type = os.environ.get("STORAGE_TYPE", "")
    if not bucket_name or not storage_type:
        logging.error(f'Missing or incorrect configuration, bucket_name: {bucket_name}, storage_type: {storage_type}')
        return
    file_name = "kevc_cves_data"
    kevc_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    stored_data = get_kevc_local_data(bucket_name, file_name, storage_type) or {}
    last_modified = stored_data.get("last_modified")
    active_exploit_cves = stored_data.get("active_exploit_cves", [])

    fresh_data, last_modified = get_kevc_cisa_data(kevc_url, last_modified)
    if not fresh_data and not last_modified:
        logging.debug('No KEVC data to update, exiting.')
        return

    new_cves_count = 0
    for data in fresh_data.get("vulnerabilities", []):
        cve_id = data.get("cveID")
        if cve_id not in active_exploit_cves:
            new_cves_count += 1
            active_exploit_cves.append(cve_id)

    logging.info(f'Updating {new_cves_count} new exploitable cve records')

    stored_data.update({
        'last_modified': last_modified,
        'active_exploit_cves': active_exploit_cves
    })

    update_kevc_local_data(bucket_name, file_name, stored_data, storage_type)


def check_cve_kevc_status(cve):
    has_active_exploit = False
    bucket_name = os.environ.get("BUCKET_NAME")
    storage_type = os.environ.get("STORAGE_TYPE", "")
    allowed_storage_medium = [STORAGE_S3, STORAGE_LOCAL]
    if not bucket_name or not storage_type or storage_type not in allowed_storage_medium:
        logging.error(f'Missing or incorrect configuration, bucket_name: {bucket_name}, storage_type: {storage_type}')
        return
    try:
        file_name = "kevc_cves_data"
        stored_data = get_kevc_local_data(bucket_name, file_name, storage_type) or {}
        active_exploit_cves = stored_data.get("active_exploit_cves", [])
        has_active_exploit = cve in active_exploit_cves
    except Exception as e:
        logging.exception(e)
    return has_active_exploit
